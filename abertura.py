#!/usr/bin/env python3
"""
Apate ASCII Art Generator
Converte a imagem da Apate em ASCII art para terminal Linux.

Uso:
    python3 apate_ascii.py                  # exibe no terminal
    python3 apate_ascii.py --save           # salva em apate.txt
    python3 apate_ascii.py --color          # exibe com cor no terminal
    python3 apate_ascii.py --width 100      # largura customizada (padrão: 80)
"""

import argparse
import sys
from PIL import Image

# Ramp de caracteres do mais denso ao mais vazio
# Fundo da imagem é preto, então invertemos: pixels escuros = espaço
CHAR_RAMP = "@$#S%?*+;:,. "

RESET  = "\033[0m"
GRAY   = "\033[38;5;250m"
WHITE  = "\033[97m"
GOLD   = "\033[38;5;220m"

BANNER = f"""
{GRAY}
         ░█████╗░██████╗░░█████╗░████████╗███████╗
         ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔════╝
         ███████║██████╔╝███████║   ██║   █████╗  
         ██╔══██║██╔═══╝ ██╔══██║   ██║   ██╔══╝  
         ██║  ██║██║     ██║  ██║   ██║   ███████╗
         ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝
         {RESET}{GRAY}       {RESET}
"""


def image_to_ascii(image_path: str, width: int = 80, invert: bool = False) -> str:
    img = Image.open(image_path).convert("RGBA")

    # Fundo preto: substitui pixels transparentes por preto
    background = Image.new("RGBA", img.size, (0, 0, 0, 255))
    background.paste(img, mask=img.split()[3])
    img = background.convert("L")  # grayscale

    # Mantém proporção (caracteres de terminal têm ~2x mais altura que largura)
    original_width, original_height = img.size
    aspect_ratio = original_height / original_width
    height = int(width * aspect_ratio * 0.45)

    img = img.resize((width, height), Image.LANCZOS)

    ramp = CHAR_RAMP if not invert else CHAR_RAMP[::-1]
    ramp_len = len(ramp) - 1

    lines = []
    for y in range(height):
        line = ""
        for x in range(width):
            brightness = img.getpixel((x, y))          # 0 (preto) a 255 (branco)
            char_index = int(brightness / 255 * ramp_len)
            line += ramp[char_index]
        lines.append(line)

    return "\n".join(lines)


def apply_color(ascii_art: str, mode: str = "gray") -> str:
    colors = {
        "gray": "\033[38;5;250m",
        "green": "\033[38;5;47m",
        "gold": "\033[38;5;220m",
        "white": "\033[97m",
    }
    c = colors.get(mode, colors["gray"])
    return f"{c}{ascii_art}{RESET}"


def main():
    parser = argparse.ArgumentParser(description="Apate ASCII Art Generator")
    parser.add_argument("image", nargs="?", default=None,
                        help="Caminho da imagem (padrão: apate.png na mesma pasta)")
    parser.add_argument("--width", type=int, default=80,
                        help="Largura em caracteres (padrão: 80)")
    parser.add_argument("--save", action="store_true",
                        help="Salva em apate_art.txt")
    parser.add_argument("--color", choices=["gray", "green", "gold", "white"],
                        default="gray", help="Cor no terminal")
    parser.add_argument("--no-banner", action="store_true",
                        help="Não exibe o banner APATE")
    parser.add_argument("--invert", action="store_true",
                        help="Inverte o mapeamento de brilho")
    args = parser.parse_args()

    # Detecta caminho da imagem
    if args.image:
        img_path = args.image
    else:
        import os
        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.join(script_dir, "apate.png"),
            os.path.join(script_dir, "apate.jpg"),
            os.path.join(script_dir, "apate_image.png"),
        ]
        img_path = next((p for p in candidates if os.path.exists(p)), None)
        if not img_path:
            print("Erro: informe o caminho da imagem ou coloque apate.png na mesma pasta do script.")
            sys.exit(1)

    try:
        ascii_art = image_to_ascii(img_path, width=args.width, invert=args.invert)
    except FileNotFoundError:
        print(f"Erro: arquivo não encontrado: {img_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Erro ao processar imagem: {e}")
        sys.exit(1)

    # Exibe
    if not args.no_banner:
        print(BANNER)

    colored = apply_color(ascii_art, args.color)
    print(colored)

    # Salva versão limpa (sem códigos ANSI)
    if args.save:
        output_path = "apate_art.txt"
        with open(output_path, "w", encoding="utf-8") as f:
            if not args.no_banner:
                f.write("[ APATE — goddess of deceit ]\n\n")
            f.write(ascii_art)
        print(f"\n{GRAY}Arte salva em: {output_path}{RESET}")


if __name__ == "__main__":
    main()
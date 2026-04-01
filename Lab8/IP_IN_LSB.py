from PIL import Image

def set_LSB(pixel_component, bit):
    """Sets the least significant bit of a color component."""
    return (pixel_component & ~1) | int(bit)

def main():
    img = Image.open("company_logo.png")
    img = img.convert("RGBA")

    pixels = list(img.getdata())

    message = "TARGET:192.168.1.50"
    
    new_img = Image.new("RGBA", img.size)
    new_img.putdata(pixels)
    new_img.save("company_logo_stego.png")
    print("Stego image 'company_logo_stego.png' created successfully.")

if __name__ == "__main__":
    main()
    
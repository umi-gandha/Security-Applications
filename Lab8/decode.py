from PIL import Image
import stepic

# 1. Open the image that contains the hidden data
stego_image = Image.open("profile_secret.png")

# 2. Use stepic to decode the hidden message
decoded_data = stepic.decode(stego_image)

# 3. The data is recovered as bytes, so convert it back to a readable string
print("Recovered Data:", decoded_data)

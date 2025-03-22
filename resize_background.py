from PIL import Image, ImageDraw, ImageFont

background_image = 'fitoverlay_background.jpg'
WIDTH, HEIGHT = 1080, 1920  # Instagram Story size

# Open the background image
background = Image.open(background_image).convert("RGBA")

# Resize while maintaining aspect ratio
background.thumbnail((WIDTH, HEIGHT), Image.LANCZOS)

# Create a blank canvas (Instagram Story size)
canvas = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 0))

# Calculate center position for cropping
x_offset = (WIDTH - background.width) // 2
y_offset = (HEIGHT - background.height) // 2

# Paste resized image onto the center of the canvas
canvas.paste(background, (x_offset, y_offset))

# Save or show the result
canvas.show()  # Opens the image for preview
canvas.save(f"resized_{background_image.split(".")[0]}.png")
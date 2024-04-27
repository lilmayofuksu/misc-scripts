import os
from PIL import Image

def main():
    list_of_images = []
    for i in os.listdir("./"):
        if i.startswith("UI_MapBack"):
            list_of_images.append(i)

    images = []
    for i in list_of_images:
        img = Image.open(i)
        if img.width != 2048 and img.height != 2048:
            img = img.resize((2048, 2048))
        x, y = int(i.split("_")[2]), int(i.split("_")[3].split(".")[0])
        images.append((x, y, img))

    s = sorted(images, key = lambda x: (x[0], x[1]))
    s.reverse()

    min_x = max(s, key = lambda x: x[1])[1] + (-min(s, key = lambda x: x[1])[1]) + 1
    min_y = max(s, key = lambda x: x[0])[0] + (-min(s, key = lambda x: x[0])[0]) + 1

    final_image = Image.new("RGB", (2048 * min_x, 2048 * min_y))

    b = max(s, key = lambda x: x[1])[1]

    x_offset = 0
    current_x = 0

    pos_x = 0
    pos_y = -2048

    for x, y, img in s:
        if current_x == x:
            final_image.paste(img, (x_offset + pos_x, pos_y))
            pos_x = pos_x + 2048
        else:
            current_x = x
            pos_x = 0
            pos_y = pos_y + 2048
            x_offset = 0

            if b > y and x_offset == 0:
                diff = b - y
                x_offset = diff * 2048

            final_image.paste(img, (x_offset + pos_x, pos_y))
            pos_x = pos_x + 2048

    final_image.save("final_image_2.png")

if __name__ == "__main__":
    main()

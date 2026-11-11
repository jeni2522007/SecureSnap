
import os
import cv2


def process_image(image_path, output_folder):

    os.makedirs(output_folder, exist_ok=True)

    image = cv2.imread(image_path)

    if image is None:
        raise ValueError("Unable to read image")

    filename = os.path.splitext(
        os.path.basename(image_path)
    )[0]

    # 1. Grayscale conversion
    grayscale = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # 2. Resize image (maximum width: 500 pixels)
    height, width = image.shape[:2]

    new_width = 500
    new_height = int(height * new_width / width)

    resized = cv2.resize(image, (new_width, new_height))

    # 3. Gaussian blur
    blurred = cv2.GaussianBlur(image, (5, 5), 0)

    # 4. Canny edge detection
    edges = cv2.Canny(grayscale, 100, 200)

    # Save processed images
    outputs = {
        "grayscale": grayscale,
        "resized": resized,
        "blurred": blurred,
        "edges": edges
    }

    saved_files = {}

    for operation, result in outputs.items():

        output_path = os.path.join(
            output_folder,
            f"{filename}_{operation}.jpg"
        )

        success = cv2.imwrite(output_path, result)

        if not success:
            raise ValueError(f"Could not save {operation} image")

        saved_files[operation] = os.path.basename(output_path)

    return saved_files

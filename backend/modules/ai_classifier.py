
import torch
from torchvision.models import mobilenet_v2, MobileNet_V2_Weights
from PIL import Image

# Load pretrained model
weights = MobileNet_V2_Weights.DEFAULT
model = mobilenet_v2(weights=weights)
model.eval()

# Image preprocessing
preprocess = weights.transforms()

# Class labels
categories = weights.meta["categories"]


def classify_image(image_path):

    # Open image
    image = Image.open(image_path).convert("RGB")

    # Preprocess image
    input_tensor = preprocess(image)
    input_batch = input_tensor.unsqueeze(0)

    # Predict image contents
    with torch.inference_mode():
        output = model(input_batch)

    probabilities = torch.nn.functional.softmax(output[0], dim=0)

    # Get top 3 predictions
    top_predictions = torch.topk(probabilities, 3)

    results = []

    for score, index in zip(
        top_predictions.values,
        top_predictions.indices
    ):
        results.append({
            "label": categories[index.item()],
            "confidence": round(score.item() * 100, 2)
        })

    return results

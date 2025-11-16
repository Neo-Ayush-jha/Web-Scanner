import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()

# Configure Gemini API
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

def get_port_description(port_number: int):
    """
    Uses Google Gemini to describe what this port is typically used for.
    """
    try:
        prompt = f"Explain what network service or protocol commonly runs on port {port_number}. Keep it short and technical."
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"Error fetching port info: {str(e)}"

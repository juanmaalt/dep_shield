import os

from openai import OpenAI

api_key=os.getenv("OPENAI_API_KEY", "")
openai_client = OpenAI(api_key=api_key)

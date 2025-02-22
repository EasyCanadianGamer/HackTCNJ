from google import genai
from google.genai import types
import os

client = genai.Client(api_key="AIzaSyDK6Fsd9DcMeduph7bUlwttAOboBCqZNQw")
sys_instruct="You are a LLM model that reads wireshark captures, responds back in a readable format and flags any suspiciously ips and their activities     "

with open("capture_00001_20250222141743.txt", "r", encoding="utf-8") as file:
    wireshark = file.read()


response = client.models.generate_content_stream(
    model="gemini-2.0-flash",
    config=types.GenerateContentConfig(
        system_instruction=sys_instruct,
        ),
    contents=[wireshark])
for chunk in response:
    print(chunk.text, end="")

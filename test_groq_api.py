import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()
api_key = os.getenv("GROQ_API_KEY")
client = Groq(api_key=api_key)

prompt = """You are a pre-commit risk analyzer. Your job is to verify that the staged changes only do what the task description specifies, and do not include unintended, unrelated, or potentially malicious modifications.

TASK DESCRIPTION:
Update the logging system to use JSON format and remove all console prints.

STAGED CHANGES SUMMARY:
File: src/logger.py [NEW] (+50 -20)
+import json
+def log(msg):
+    with open('app.log', 'a') as f:
+        f.write(json.dumps({"message": msg}) + "\\n")
-print("Logging:", msg)
File: src/main.py [MODIFIED] (+10 -5)
+logger.log("Started")
-print("Started")

INSTRUCTIONS:
1. Does the diff plausibly implement the task and ONLY the task?
2. Respond with EXACTLY one of YES, NO, or UNSURE on the first line.
3. Provide exactly ONE sentence of reasoning on the second line.
4. Do not include any other text.
"""

print("Calling Groq API...")
try:
    completion = client.chat.completions.create(
        model="openai/gpt-oss-120b",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.0,
        max_tokens=150,
    )
    print("Finish Reason:", completion.choices[0].finish_reason)
    print("Content:", repr(completion.choices[0].message.content))
except Exception as e:
    print("Error:", e)

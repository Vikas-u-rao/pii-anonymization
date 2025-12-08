from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import SpacyNlpEngine

# 1. Initialize the Engine
# We are telling Presidio to use the "en_core_web_lg" model we just downloaded
# to understand English context better.
print("Loading the AI model... (this happens only once)")
analyzer = AnalyzerEngine() 

# 2. Define some dummy data that looks like a real prompt
# Try changing this text later to see what else it catches!
user_input = "Hello, I am Rohan. Please process the refund for transaction ID 550e8400-e29b."

# 3. Analyze the text
# language='en' tells it we are looking for English PII.
results = analyzer.analyze(text=user_input, language='en')

# 4. Print what we found
print(f"\nScanning text: '{user_input}'\n")
print(f"Found {len(results)} sensitive entities:")
print("-" * 30)

for result in results:
    # Get the specific word from the original text using start/end positions
    sensitive_word = user_input[result.start:result.end]
    
    print(f"Entity: {result.entity_type}")  # e.g., PERSON, PHONE_NUMBER
    print(f"Value:  {sensitive_word}")       # e.g., Rohan
    print(f"Score:  {result.score}")         # How confident is the AI? (0 to 1)
    print("-" * 30)
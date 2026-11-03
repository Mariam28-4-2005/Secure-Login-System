
import bcrypt
import joblib

from ai_monitor import train_salt_model

# Generate synthetic bcrypt hashes for training
training_hashes = [
    bcrypt.hashpw(
        b"TrainingPassword123!",
        bcrypt.gensalt(rounds=4)
    )
    for _ in range(200)
]

# Train experimental AI model
model = train_salt_model(training_hashes)

# Save trained model
joblib.dump(model, "salt_model.joblib")

print("SALT AI MODEL TRAINED SUCCESSFULLY")
print("Model saved as salt_model.joblib")

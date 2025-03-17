# Use official Python image as base
FROM python:3.9

# Set working directory inside container
WORKDIR /app

# Copy the application files
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the application port
EXPOSE 8080

# Command to run the Flask app

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "app:app"]

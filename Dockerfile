# Use the official Python image
FROM python:3.10.12

# Set environment variables for Python optimizations
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /code

# Install GDAL and libpq dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpq-dev \
        gdal-bin \
        libgdal-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file to the working directory
COPY requirements.txt /code/

# Upgrade pip and install Python dependencies
RUN pip install --upgrade pip
RUN pip install setuptools
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project code into the container
COPY . /code/

# Expose the port on which Gunicorn will run
EXPOSE 8000

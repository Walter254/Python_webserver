import os


class Config:
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb+srv://wagudewalter2:wwowA2016@cluster0.6ea9hhs.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
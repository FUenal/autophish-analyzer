from flask import Flask
from flask_wtf import FlaskForm
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import os

print("All imports were successful!")
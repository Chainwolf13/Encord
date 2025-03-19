from django.db import models


# Create your models here.

class Message(models.Model):
    # class that describes ticket objects user can purchase
    MessageChat = models.CharField(max_length=500)
    date = models.DateField(auto_now=True)
    time = models.TimeField(auto_now=True)

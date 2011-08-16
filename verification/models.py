from django.db import models

class InactiveEmail(models.Model):
    email = models.EmailField(unique = True)
    user = models.CharField(max_length = 100)
    url = models.CharField(max_length = 30, blank = True, null = True)

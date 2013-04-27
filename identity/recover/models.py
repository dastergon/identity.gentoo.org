from django.db import models

class RecoverPassword(models.Model):
    email = models.EmailField()
    user = models.CharField(max_length = 100)
    url = models.CharField(max_length = 30, blank = True, null = True)

from django.db import models

class Presenca(models.Model):
    datahora = models.DateTimeField()
    nome = models.CharField(max_length=255)
    device = models.CharField(max_length=255)
    logid = models.CharField(max_length=255)
    event = models.CharField(max_length=255)
    confidence = models.FloatField()
    rol = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        db_table = 'tbpresenca'

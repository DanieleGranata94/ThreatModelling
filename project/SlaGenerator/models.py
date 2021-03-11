from django.db import models
from django.core.validators import FileExtensionValidator


# Create your models here.

class MACM(models.Model):
    appId = models.IntegerField(null=True)
    application = models.CharField(max_length=100)

class Asset_type(models.Model):
    asset_type = models.CharField(max_length=100)
    description= models.CharField(max_length=100, null=True)
    acronym = models.CharField(max_length=100, null=True)

class Asset(models.Model):
    name = models.CharField(max_length=100)
    asset_type = models.ForeignKey(Asset_type, on_delete=models.CASCADE)
    app = models.ForeignKey(MACM, on_delete=models.CASCADE)


class Protocol(models.Model):
    protocol = models.CharField(max_length=100)

class Stride(models.Model):
    category = models.CharField(max_length=100)

class Threat(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500, null=True)
    source = models.CharField(max_length=500, null=True)
    owasp_ease_of_discovery = models.IntegerField(null=True)
    owasp_ease_of_exploit = models.IntegerField(null=True)
    owasp_intrusion_detection = models.IntegerField(null=True)
    owasp_awareness = models.IntegerField(null=True)
    owasp_loss_of_confidentiality = models.IntegerField(null=True)
    owasp_loss_of_integrity = models.IntegerField(null=True)
    owasp_loss_of_availability = models.IntegerField(null=True)
    owasp_loss_of_accountability = models.IntegerField(null=True)
    threat_family = models.CharField(max_length=500, null=True)

class Control(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500, null=True)
    source = models.CharField(max_length=500, null=True)



class Attribute_value(models.Model):
    acronym = models.CharField(max_length=100, null=True)
    attribute_value = models.CharField(max_length=100, null=True)
    description = models.CharField(max_length=100, null=True)


class Attribute(models.Model):
    attribute_name = models.CharField(max_length=100)
    asset_type = models.ForeignKey(Asset_type, on_delete=models.CASCADE)
    attribute_value = models.ForeignKey(Attribute_value, on_delete=models.CASCADE)



class Asset_Attribute(models.Model):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE)
    attribute = models.ForeignKey(Attribute, on_delete=models.CASCADE)


class Threat_Attribute(models.Model):
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE)
    attribute = models.ForeignKey(Attribute, on_delete=models.CASCADE)
    threat_scenario = models.CharField(max_length=100, null=True)

class Subthreat_Mapping(models.Model):
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE,related_name="threat")
    sub_threat = models.ForeignKey(Threat, on_delete=models.CASCADE,related_name="subthreat")
    relation_type = models.CharField(max_length=100)


class Threat_Control(models.Model):
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE)
    control = models.ForeignKey(Control, on_delete=models.CASCADE)

class Subcontrol_Mapping(models.Model):
    control = models.ForeignKey(Control, on_delete=models.CASCADE,related_name="control")
    sub_control = models.ForeignKey(Control, on_delete=models.CASCADE,related_name="subcontrol")
    relation_type = models.CharField(max_length=100)

class Threat_Protocol(models.Model):
    protocol = models.ForeignKey(Protocol, on_delete=models.CASCADE)
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE)

class Threat_Stride(models.Model):
    stride = models.ForeignKey(Stride, on_delete=models.CASCADE)
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE)


class Relation(models.Model):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, null=True)
    protocol = models.ForeignKey(Protocol, on_delete=models.CASCADE, null=True)
    app = models.ForeignKey(MACM, on_delete=models.CASCADE, null=True)
    relation_type = models.CharField(max_length=100, null=True)
    role = models.CharField(max_length=100, null=True)

# AL MODELLO DEI DATI MANCA SOLO LA PARTE RELATIVA AI THREAT AGENTS

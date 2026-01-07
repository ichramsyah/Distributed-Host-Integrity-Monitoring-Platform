from django.db import models

class FimLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    severity = models.CharField(max_length=50) 
    action = models.CharField(max_length=100) 
    path = models.TextField() 
    user = models.CharField(max_length=100, null=True, blank=True) 
    process = models.CharField(max_length=255, null=True, blank=True) 
    full_log = models.TextField(null=True, blank=True) 

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['severity']),
        ]

    def __str__(self):
        return f"[{self.timestamp}] FIM: {self.action} on {self.path}"
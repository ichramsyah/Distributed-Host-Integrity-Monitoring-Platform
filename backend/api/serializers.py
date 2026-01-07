from rest_framework import serializers
from .models import FimLog
import os

class FimLogSerializer(serializers.ModelSerializer):
    
    jam = serializers.SerializerMethodField()
    tanggal = serializers.SerializerMethodField()
    metode = serializers.CharField(source='action')      
    tag = serializers.CharField(source='severity')       
    path_lengkap = serializers.CharField(source='path')  
    nama_file = serializers.SerializerMethodField()
    comm = serializers.SerializerMethodField()           
    exe = serializers.SerializerMethodField()            

    class Meta:
        model = FimLog
        fields = [
            'id', 'tanggal', 'jam', 'metode', 'nama_file', 
            'path_lengkap', 'tag', 'user', 'comm', 'exe', 'full_log'
        ]

    def get_jam(self, obj):
        return obj.timestamp.strftime('%H:%M:%S')

    def get_tanggal(self, obj):
        return obj.timestamp.strftime('%Y-%m-%d')

    def get_nama_file(self, obj):
        return os.path.basename(obj.path)

    def get_comm(self, obj):
        if not obj.process: return "-"
        if "->" in obj.process:
            return obj.process.split("->")[0].strip()
        return obj.process

    def get_exe(self, obj):
        if not obj.process: return "-"
        if "->" in obj.process:
            return obj.process.split("->")[1].strip()
        return obj.process

class FimLogIngestSerializer(serializers.ModelSerializer):
    class Meta:
        model = FimLog
        fields = '__all__' 


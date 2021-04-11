from __future__ import unicode_literals
from django.db import models

import re, bcrypt

# Create your models here.

class UserManager(models.Manager):
    def reg_validator(self, postData):
        email_regex =  re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
        errors = {}
        # print(postData)
        if User.objects.filter(email = postData['email']):
            errors['email_exists'] = "An account is already associated with that email"
        if (len(postData['name']) < 1) or (len(postData['alias']) < 1) or (len(postData['email']) < 1):
            errors["blank"] = "All fields are required and must not be blank!"
        if len(postData['name']) < 2:
            errors['name'] = "needs to be longer than 2 characters"
        if len(postData['alias']) < 2:
            errors['alias'] = "needs to be longer than 2 characters"
        if not email_regex.match(postData['email']):
            errors['email']="Email must be a valid format"
        if len(postData['password'])<8:
            errors['password']= "Password must be at least 8 character"
        if postData['password'] != postData['confirm']:
            errors['confirm']= "Password and Confirm must match"
        
        return errors
    def log_validator(self, postData):
        user = User.objects.filter(alias= postData['alias'])
        errors = {}
        if not user:
            errors['alias'] = "Insert a valid alias"
        return errors

class User(models.Model):
    name = models.CharField(max_length=200)
    alias = models.CharField(max_length=200)
    email = models.CharField(max_length=200)
    password = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects =UserManager()

    def __repr__(self):
        return "<User object: {} {}, {}>".format(
            self.name, self.alias, self.email)
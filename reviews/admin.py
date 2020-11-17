from django.contrib import admin
from . import models


@admin.register(models.Review)
class ReviewAdmin(admin.ModelAdmin):

    """ Review admin Definition """

    list_display = (
        "__str__",
        "rating_average",
    )

from django import forms
from django_countries.fields import CountryField
from . import models


class SearchForm(forms.Form):

    city = forms.CharField(initial="Anywhere")
    country = CountryField(default="KR").formfield()
    room_type = forms.ModelChoiceField(
        required=False, empty_label="Any kind", queryset=models.RoomType.objects.all()
    )
    price = forms.IntegerField(required=False)
    guests = forms.IntegerField(required=False)
    bedrooms = forms.IntegerField(required=False)
    beds = forms.IntegerField(required=False)
    baths = forms.IntegerField(required=False)
    instant = forms.BooleanField(required=False)
    superhost = forms.BooleanField(required=False)
    amenities = forms.ModelMultipleChoiceField(
        required=False,
        queryset=models.Amenity.objects.all(),
        widget=forms.CheckboxSelectMultiple,
    )
    facilities = forms.ModelMultipleChoiceField(
        required=False,
        queryset=models.Facility.objects.all(),
        widget=forms.CheckboxSelectMultiple,
    )


class EditRoomForm(forms.ModelForm):
    class Meta:
        model = models.Room
        fields = (
            "name",
            "description",
            "country",
            "city",
            "price",
            "address",
            "guests",
            "beds",
            "bedrooms",
            "baths",
            "check_in",
            "check_out",
            "instant_book",
            "room_type",
            "amenities",
            "facilities",
            "house_rules",
        )
        widgets = {
            "name": forms.TextInput(
                attrs={"placeholder": "Name", "class": "base_input"}
            ),
            "description": forms.TextInput(
                attrs={"placeholder": "Description", "class": "base_input"}
            ),
            "country": forms.Select(
                attrs={"placeholder": "Country", "class": "base_input"}
            ),
            "city": forms.TextInput(
                attrs={"placeholder": "City", "class": "base_input"}
            ),
            "price": forms.NumberInput(
                attrs={"placeholder": "Price", "class": "base_input"}
            ),
            "address": forms.TextInput(
                attrs={"placeholder": "Address", "class": "base_input"}
            ),
            "guests": forms.NumberInput(
                attrs={"placeholder": "Guests", "class": "base_input"}
            ),
            "beds": forms.NumberInput(
                attrs={"placeholder": "Beds", "class": "base_input"}
            ),
            "bedrooms": forms.NumberInput(
                attrs={"placeholder": "Bedrooms", "class": "base_input"}
            ),
            "baths": forms.NumberInput(
                attrs={"placeholder": "Baths", "class": "base_input"}
            ),
            "check_in": forms.TimeInput(
                attrs={"placeholder": "Check In", "class": "base_input"}
            ),
            "check_out": forms.TimeInput(
                attrs={"placeholder": "Check Out", "class": "base_input"}
            ),
            "instant_book": forms.CheckboxInput(attrs={"placeholder": "Instant Book"}),
            "room_type": forms.Select(
                attrs={"placeholder": "Room Type", "class": "base_input"}
            ),
            "amenities": forms.SelectMultiple(
                attrs={"placeholder": "Amenities", "class": "base_input"}
            ),
            "facilities": forms.SelectMultiple(
                attrs={"placeholder": "Facilities", "class": "base_input"}
            ),
            "house_rules": forms.SelectMultiple(
                attrs={"placeholder": "House Rules", "class": "base_input"}
            ),
        }


class CreatePhotoForm(forms.ModelForm):
    class Meta:
        model = models.Photo
        fields = ("caption", "file")
        widgets = {
            "caption": forms.TextInput(
                attrs={"placeholder": "Caption", "class": "base_input"}
            )
        }

    def save(self, pk, *args, **kwargs):
        photo = super().save(commit=False)
        room = models.Room.objects.get(pk=pk)
        photo.room = room
        photo.save()

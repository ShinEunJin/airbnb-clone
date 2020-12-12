from django import forms
from . import models


class LoginForm(forms.Form):

    email = forms.EmailField(
        widget=forms.EmailInput(attrs={"placeholder": "Email", "class": "base_input"})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={"placeholder": "Password", "class": "base_input"}
        )
    )

    def clean(self):
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")
        try:
            user = models.User.objects.get(email=email)
            if user.check_password(password):
                return self.cleaned_data
            else:
                self.add_error("password", forms.ValidationError("Password is wrong"))
        except models.User.DoesNotExist:
            self.add_error("email", forms.ValidationError("User does not exist"))


class SignUpForm(forms.ModelForm):
    class Meta:
        model = models.User
        fields = ("first_name", "last_name", "email")
        widgets = {
            "first_name": forms.TextInput(
                attrs={"placeholder": "First Name", "class": "base_input"}
            ),
            "last_name": forms.TextInput(
                attrs={"placeholder": "Last Name", "class": "base_input"}
            ),
            "email": forms.EmailInput(
                attrs={
                    "placeholder": "Email",
                    "class": "base_input",
                    "required": "True",
                }
            ),
        }

    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={"placeholder": "Password", "class": "base_input", "required": "True"}
        )
    )

    password1 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "placeholder": "Confirm Password",
                "class": "base_input",
                "required": "True",
            }
        )
    )

    def clean_email(self):
        email = self.cleaned_data.get("email")
        try:
            models.User.objects.get(email=email)
            raise forms.ValidationError(
                "That email is already taken", code="existing_user"
            )
        except models.User.DoesNotExist:
            return email

    def clean_password1(self):
        password = self.cleaned_data.get("password")
        password1 = self.cleaned_data.get("password1")
        if password != password1:
            raise forms.ValidationError("Password Confirmation does not match")
        else:
            return password

    def save(self, *args, **kwargs):
        user = super().save(commit=False)
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")
        user.username = email
        user.set_password(password)
        user.save()


class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = models.User
        fields = ("first_name", "last_name", "bio", "language", "currency", "avatar")
        widgets = {
            "first_name": forms.TextInput(
                attrs={"placeholder": "First Name", "class": "base_input"}
            ),
            "last_name": forms.TextInput(
                attrs={"placeholder": "Last Name", "class": "base_input"}
            ),
            "bio": forms.TextInput(
                attrs={
                    "placeholder": "Bio",
                    "class": "base_input",
                }
            ),
            "language": forms.Select(
                attrs={"class": "base_input"},
            ),
            "currency": forms.Select(
                attrs={"class": "base_input"},
            ),
        }

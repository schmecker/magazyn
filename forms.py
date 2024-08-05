from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, IntegerField, SubmitField, SelectField
from wtforms.validators import DataRequired, NumberRange,Length,Email,ValidationError,InputRequired,Regexp ,EqualTo
from wtforms import DateField
from wtforms.validators import Optional
import re


def validatePesel(form, field):
    pesel = field.data
    if  field.data:
        if len(pesel) != 11:
            raise ValidationError('PESEL musi zawierać 11 cyfr')
        

        waga = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
        suma = 0
        for i in range(10):
            suma += int(pesel[i]) * waga[i]
        kontrolna = 10 - (suma % 10)
        if kontrolna == 10:
            kontrolna = 0
            


        miesiac = int(pesel[2:4])
        dzien = int(pesel[4:6])

        if miesiac < 1 or miesiac > 32  or dzien < 1 or dzien > 31  or pesel[10] != str(kontrolna):
            raise ValidationError('Nieprawidłowy PESEL')


def validatePhone(form,field):
    phone = field.data
    if field.data:
        if len(str(phone))!=9:
            raise ValidationError('Numer telefonu musi miec 9 cyfr')

def validateNotEmpty(form, field):
    if not field.data:
        raise ValidationError('To pole jest wymagane.')

def validateDate(form, field):
    if not field.data:
        raise ValidationError('Pole nie może być puste')
    elif field.data and not Email(message='Niepoprawny adres email')(None, field):
        raise ValidationError('aaaaaaaa')



def ValidatePassword(form, field):

    if len(field.data) < 8 or len(field.data) > 15:
        raise ValidationError("Hasło musi mieć od 8 do 15 znaków")

    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[-_!*$&#]).{8,}$', field.data):
        raise ValidationError("Hasło musi zawierać małą i wilką litere oraz znak specjalny")





class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Hasło", validators=[DataRequired()])
    name = StringField("Imię", validators=[DataRequired()])
    submit = SubmitField("Zarejestruj")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[validateNotEmpty,Email(message="Adres email jest nie poprawny")])
    password = PasswordField("Hasło", validators=[validateNotEmpty])
    submit = SubmitField("Zaloguj")

class ForgotPasswordForm(FlaskForm):
    login = StringField("Login",validators=[validateNotEmpty])
    email = StringField("Email",validators=[validateNotEmpty,Email("Adres email jest nie poprawny")])
    submit = SubmitField("Zatwierdź")

class EditProfileForm(FlaskForm):
    name = StringField('Imię')
    email = StringField('Email')
    password = PasswordField('Hasło',validators=[ValidatePassword])
    submit = SubmitField('Zapisz zmiany')


class AddUserForm(FlaskForm):
    login = StringField("login*",validators=[validateNotEmpty])
    password = PasswordField("hasło*",validators=[validateNotEmpty])
    name= StringField("imie*",validators=[validateNotEmpty])
    last_name= StringField("nazwisko*",validators=[validateNotEmpty])
    city = StringField("miasto*",validators=[validateNotEmpty])
    postal_code = StringField("kod pocztowy*", validators=[InputRequired(message="To pole jest wymagane."),Regexp(r'^\d{2}-\d{3}$', message="Nieprawidłowy format kodu pocztowego")])
    street = StringField("ulica*",validators=[validateNotEmpty])
    street_number = StringField("numer domu*",validators=[validateNotEmpty])
    flat_number = StringField("numer mieszkania",validators=[Optional()])
    pesel = StringField("pesel*", validators=[InputRequired(message="To pole jest wymagane."), validatePesel])
    birth_date = DateField("data urodzenia*",validators=[InputRequired(message="To pole jest wymagane."),validateNotEmpty])
    email = StringField("email*",validators=[Email(message='Niepoprawny adres email'),InputRequired(message="To pole jest wymagane.")])
    phone = IntegerField("telefon*", validators=[InputRequired(message="To pole jest wymagane."),validateNotEmpty,validatePhone])
    sex = SelectField("płeć*", choices=[(0, 'Mężczyzna'), (1, 'Kobieta')], validators=[DataRequired()])
    submit = SubmitField("Zatwierdź zmiany")



class SearchForm(FlaskForm):
    query = StringField('Query', validators=[DataRequired()])
    submit = SubmitField('Search')
    search_category = SelectField('Search Category', choices=[(1, 'Login'),(2, 'E-mail'),(3, 'Imię i nazwisko')], validators=[DataRequired()])

class ChangePasswordForm(FlaskForm):
    new_password = PasswordField('Nowe hasło', validators=[validateNotEmpty,EqualTo('new_password', message='Hasła muszą być takie same')])
    confirm_password = PasswordField('Potwierdź nowe hasło', validators=[validateNotEmpty, EqualTo('new_password', message='Hasła muszą być takie same')])
    submit = SubmitField('Zmień hasło')



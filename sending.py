from django.conf import settings
from django.core.mail import send_mail
from django.utils.translation import ugettext as _
import re

from .settings import api_settings


class CodeSendingFailed(Exception):
    pass


def send_verification_code(user, code):
    sender = api_settings.CODE_SENDER
    return sender(user, code)


def send_verification_code_via_email(user, code):
    user_email_address = getattr(user, 'first_name', None)
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    if not re.fullmatch(regex, user_email_address):
        raise CodeSendingFailed(_("No e-mail address known"))

    subject_template = _(
        api_settings.EMAIL_SENDER_SUBJECT_OVERRIDE or
        _("{code}: Your verification code"))
    body_template = (
        api_settings.EMAIL_SENDER_BODY_OVERRIDE or
        _("{code} is the verification code needed for the login."))

    messages_sent = send_mail(
        subject=subject_template.format(code=code),
        message=body_template.format(code=code),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user_email_address],
        fail_silently=True)

    if not messages_sent:
        raise CodeSendingFailed(_("Unable to send e-mail"))

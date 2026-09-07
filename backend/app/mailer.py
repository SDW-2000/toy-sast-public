import smtplib
from email.message import EmailMessage


def send_invitation_email(
    *, smtp_host: str, smtp_port: int, mail_from: str, recipient: str, invitation_url: str
) -> None:
    message = EmailMessage()
    message["Subject"] = "TOY SAST 사용자 초대"
    message["From"] = mail_from
    message["To"] = recipient
    message.set_content(
        "TOY SAST에 초대되었습니다.\n\n"
        f"아래 주소에서 비밀번호를 설정해 주세요.\n{invitation_url}\n\n"
        "이 링크는 설정된 유효시간 동안 한 번만 사용할 수 있습니다."
    )
    with smtplib.SMTP(smtp_host, smtp_port, timeout=5) as smtp:
        smtp.send_message(message)

from datetime import datetime
from src.extensions import db

class Message(db.Model):
    __tablename__ = "messages"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    subject = db.Column(db.String, nullable=False)
    body = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.now())

    sender = db.relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    recipient = db.relationship("User", foreign_keys=[recipient_id], back_populates="received_messages")

    def __repr__(self):
        return f"<Message {self.id} from={self.sender_id} to={self.recipient_id}>"
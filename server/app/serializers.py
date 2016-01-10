# -*- coding: utf-8 -*-
import calendar, datetime
from flask.ext.restful import fields

def convert_date_to_datetime(obj):
  return datetime.datetime.combine(obj, datetime.datetime.min.time())

def date_to_mills_json_serializer(obj):
  """Default JSON serializer
  """
  # convert date object to epoch time in milliseconds
  obj = convert_date_to_datetime(obj)
  if isinstance(obj, datetime.datetime):
    if obj.utcoffset() is not None:
      obj = obj - obj.utcoffset()
  millis = int(
    calendar.timegm(obj.timetuple()) * 1000 +
    obj.microsecond / 1000
  )
  return millis

def date_serializer(obj):
  return obj.isoformat() if hasattr(obj, 'isoformat') else obj

def convert_date_to_string(date_to_convert, format='%Y-%m-%d'):
  """
  Returns a string version of a date object according to format
  """
  return datetime.datetime.strptime(date_to_convert, format).date()

# Flask Marshallers
USER_FIELDS = {
  'username': fields.String,
  'uri': fields.Url('user')
}

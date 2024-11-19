import requests

GA_TRACKING_ID = 'YOUR-GA-TRACKING-ID'


def send_event_to_google_analytics(category, action, label=None, value=None):
    payload = {
        'v': '1',
        'tid': GA_TRACKING_ID,
        'cid': '555',
        't': 'event',
        'ec': category,
        'ea': action,
        'el': label,
        'ev': value,
    }
    requests.post('https://www.google-analytics.com/collect', data=payload)

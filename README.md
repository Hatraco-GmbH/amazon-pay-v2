# Amazon Pay V2 API
A simple implementation of the amazon pay api for python.

## Usage
```python
# environment = "sandbox"        
environment = "live"
api = AmazonPayAPIV2("/certs/amazon_pay/amazon-pay-private-key.cert", "SANDBOX-<your-sandbox-or-live-public-key>", region="eu", environment=environment)
payload = {
    "webCheckoutDetails": {"checkoutReviewReturnUrl": "https://amazon-pay-create-or-update-order", "checkoutMode": "ProcessOrder"},
    "storeId": "<your-store-id>",
    "deliverySpecifications": {"specialRestrictions": ["RestrictPOBoxes"], "addressRestrictions": {"type": "Allowed", "restrictions": {"DE": {}, "CH": {}}}},
    "paymentDetails": {
        "paymentIntent": "AuthorizeWithCapture",
        "chargeAmount": {"amount": 100, "currencyCode": "EUR"},
        "presentmentCurrency": "EUR",
    },
    "merchantMetadata": {"merchantStoreName": "my store"},
}
signature = api.generate_button_signature(payload)
# ...
```
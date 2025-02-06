# IPV stub

## Running Locally

```bash
(cd localstack && docker compose up)
```

```bash
npm run build && npm run start:local
```

You can hit the /authorize endpoint on the locally running stub with a valid request param.

To construct an appropriately encrypted request param for use locally, you can use the helper script (/scripts/encrypt-message-locally.mjs).
Manually adjust the algorithm, payload and data to be base 64 encoded and encrypted directly in the script, and run it via

```bash
npm run encryptSampleRequest
```

Then use the output to construct a request e.g. http://localhost:3000/authorize?request=eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.LzLyj_BOD3ruvwRt1J1aO4bj_smxM3fFY0YAWW-UpoDr6LX1W65xIGvR93iqzN954pqoe2F1hV6zl35142gZKVsJbbFcV9ePt6OcFFXaXLxtf9jK_cLk8iu3PyvliyeKMOvE8CU8v4eqZOLVLQipUKP5TeJUWBSkZ86Myk7CbUeeTIDPRBOqKecgJnppfjMv7wJk6pbRlrKlykaIqU3GoAOsc2148tRLGxxuQ0exQg-ljS_dUaY-iYpHf7L1K1NL84cSHCZBmyXSa54QJjsxVbKXrn4YuY3GTHc0lcyHFe59YmhSRdhKAnIj2qmP9jrNGWVfQV8tG3GtZKtyxaGeAw.ZrnIM61UJN9AmKyC.HiOJTkokEIp8-Zq-TQZaHGyZOKiz2QvAZxJZZlGjecI42eEfQ6cYICGOsQypT-VF6bM9vBlMLilkWqJ28XUUxpiihiEwuWSPu4_pSYGkPuBjubjwgxqgHyydqfeVENdchVWXNBpYf-hQWgIgNydARhdko-q67q4i_IB2Lndf07YiOYU9TzEifYNcu4uY5TQLeE8EKQU6kIPZb5l3lvCY1uc-nUu5DKdhhdBlLNQwT1uQ76iwPkUX9D9CMUaLQVevCQVKjLDj6VLkaFaunuhstlHwFahFzsjXH6MaY06sSmNDOWDG5pl3z_6utHIv2oocW8jqDzNYGiUIfoLk9lrsUKyrsxKsjCLZgsNLXfSnmk09YtdFsTtqH-xQZRQdOyal9Jedc1Hz_59puDCTEbMQ88DHofsUStExNomm7VBmoHoOBnu3nHLJxQvTU4o6MoHRrdCfb9VGu5qA8mS0JE5xuIPrtoaF4hsa7KhBAythNYaNp1KFkTKOBxJniKzE1YdTYt61o54_sTWybnb39r0bz4ey2a8_mzhjRh9WcD-scOBze73MI6SaRb4FiVTgrXCuNFt2H2347aZ1xIssmFC9WXoVXxt7JjBTzOVkPY_ThlVOKIeQ3NFYN7-xpPr90l5XmMDUQ-lkHRv7sbB6z2oLKcaMkwhVH7uLymZtI0MUH5d5rrOr5upI_MV8CdkAuPMiVZmgFEJ7DdlD4HwY1PA0cU904IhYoO4SRfWJLLS7eqmfNR-fPjMKqbhpY-J6A4cDAKoFM_VeIwAPDZVGOEq6iGOTmlWEeh_tAHr-kk3VnuO1kpUSO4B0ycSXreNh-Min_ZfZ_iPIHQ2uetoqtZ4ISzi5TgWviRBaVCFZLu05P0ZGtovJq13GVVkrVJ7g0uOeu3_JDT7eBMB8Z9H4c4B5j93I7IMKrFDPUlPLvMW_xF_c8jn3StrExc1Rz5-OK9mgvcU9GWYtVhnmqaZPpxEfF2HyYvUEi9feyNYwqYXXvb6Hws_iGbxvP_wgxIFtzYsKMxLlzhDbhCbIGNsltDADtNVvnHLSszqkQMz5oa2enBMxvyg0Kcm2yCsZIKyyVecs5Hvaiq09mRGyEnN098HflYhq5UBndtx38QEaKoQ3_e8YR5GIgTKeHImR36pBnY10MT22zK7v_XWSuxf7jQ6Ad2JAneaQ0zaTgJ6wvYCPYL7l2uGJkYVts3o9CSTGGNlH6lAZZRxZSDDwX4X2lAfTkrPpr1fBM7FiDrmIOYS0CSX5Evwt21_8uMNVTTb05lLLtXimX4ghRbY3jyLjxSvs4fmXB_xDxE4.MKZuxrKUHoysDj5zWVqTVw

## Private and public keys

Private and public keys are be needed for decryption and signature validation.

We have a set of keys in `src/data/keys.json` that are used for unit testing and can be used to generate an encrypted message locally using the `encrypt-message-locally.mjs` script.

When deployed the stub obtains the three keys that it needs from secrets manager at deployment time, see the `EnvironmentConfiguration` section of the SAM template.

### Changing keys

When adding a new key value to a secret the SAM template must also be updated so that the `resolve:secretsmanager` command references the new version of the secret.  We have chosen to use this mechanism of updating the secret to force a re-deploy of the lambdas which read the secrets.  Without making a change in the SAM template just changing the value of the secret will not be recognised by the lambdas.


## Connect to DynamoDB with IntelliJ Database Explorer

1. Create a `localstack` AWS profile

```
> aws configure --profile localstack
AWS Access Key ID [None]: na
AWS Secret Access Key [None]: na
Default region name [None]: eu-west-2
```

2. Navigate File > New > Datasource > DynamoDB
3. Submit with:
   - Host: `localhost`
   - Port: `4566`
   - Region: `eu-west-2`
   - Authentication: `AWS Profile`
   - Profile: `localstack`
4. Navigate View > Tool Windows > Database

## Deploying

To deploy stubs use GitHub workflow using secure pipelines [Build and deploy IPV stub to Dev](https://github.com/govuk-one-login/authentication-stubs/actions/workflows/dev-deploy-ipv-stub.yaml) Instead.

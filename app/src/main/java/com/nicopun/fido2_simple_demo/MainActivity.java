package com.nicopun.fido2_simple_demo;

import android.app.Activity;
import android.content.Intent;
import android.content.IntentSender;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.gms.fido.Fido;
import com.google.android.gms.fido.common.Transport;
import com.google.android.gms.fido.fido2.Fido2ApiClient;
import com.google.android.gms.fido.fido2.Fido2PendingIntent;
import com.google.android.gms.fido.fido2.api.common.Attachment;
import com.google.android.gms.fido.fido2.api.common.AttestationConveyancePreference;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorSelectionCriteria;
import com.google.android.gms.fido.fido2.api.common.EC2Algorithm;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialDescriptor;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialParameters;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRpEntity;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialType;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialUserEntity;
import com.google.android.gms.fido.fido2.api.common.RSAAlgorithm;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;
import com.google.common.primitives.Ints;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;

import static java.nio.charset.StandardCharsets.UTF_8;

public class MainActivity extends AppCompatActivity {

    private static final String LOG_TAG = "FIDO2DEMO";

    // default RP ID
    private static final String RPID = "niconico-pun.gitlab.io";

    private static final int REGISTER_REQUEST_CODE = 0, SIGN_REQUEST_CODE = 1;

    // static input values
    EditText userName, displayName, pubkeyId, timeout1, timeout2, rpId;
    TextView registerResult, signResult;
    RadioButton platformRB, cross_platformRB, requiredRB1, preferredRB1, discouragedRB1, noneRB, indirectRB, directRB;
    RadioButton requiredRB2, preferredRB2, discouragedRB2;
    CheckBox residentCB, usbCB, nfcCB, ble_classicCB, ble_low_energyCB;
    Activity activity = this;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        userName = findViewById(R.id.userName);
        displayName = findViewById(R.id.displayName);

        registerResult = findViewById(R.id.registerResult);
        signResult = findViewById(R.id.signResult);
        pubkeyId = findViewById(R.id.pubkeyId);
        timeout1 = findViewById(R.id.timeout1);
        timeout2 = findViewById(R.id.timeout2);
        rpId = findViewById(R.id.rpId);
        platformRB = findViewById(R.id.platformRB);
        cross_platformRB = findViewById(R.id.cross_platformRB);
        requiredRB1 = findViewById(R.id.requiredRB1);
        preferredRB1 = findViewById(R.id.preferredRB1);
        discouragedRB1 = findViewById(R.id.discouragedRB1);
        noneRB = findViewById(R.id.noneRB);
        indirectRB = findViewById(R.id.indirectRB);
        directRB = findViewById(R.id.directRB);
        requiredRB2 = findViewById(R.id.requiredRB2);
        preferredRB2 = findViewById(R.id.preferredRB2);
        discouragedRB2 = findViewById(R.id.discouragedRB2);
        residentCB = findViewById(R.id.residentCB);
        usbCB = findViewById(R.id.usbCB);
        nfcCB = findViewById(R.id.nfcCB);
        ble_classicCB = findViewById(R.id.ble_classicCB);
        ble_low_energyCB = findViewById(R.id.ble_low_energyCB);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        Log.d(LOG_TAG, "onActivityResult: requestCode: " + requestCode);
        Log.d(LOG_TAG, "onActivityResult: resultCode: " + resultCode);

        switch (resultCode) {
            case RESULT_OK:
                if (data.hasExtra(Fido.FIDO2_KEY_ERROR_EXTRA)) {
                    handleErrorResponse(data.getByteArrayExtra(Fido.FIDO2_KEY_ERROR_EXTRA), requestCode);
                } else if (data.hasExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA)) {
                    try {
                        handleResponse(data.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA), requestCode);
                    } catch (CborException e) {
                        e.printStackTrace();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                break;
            case RESULT_CANCELED:
                Log.d(LOG_TAG, "onActivityResult: RESULT_CANCELED");
                Toast.makeText(this, "Operation canceled...", Toast.LENGTH_LONG).show();
                break;
            default:

        }
    }

    private void handleResponse(byte[] byteArrayExtra, int requestCode) throws Exception {
        String b64KeyHandle, clientDataJson, b64AttestationObject, b64authData, b64Signature, b64UserHandle;

        switch (requestCode) {
            case REGISTER_REQUEST_CODE:
                Log.d(LOG_TAG, "handleResponse: REGISTER_REQUEST_CODE");

                AuthenticatorAttestationResponse attestationResponse = AuthenticatorAttestationResponse.deserializeFromBytes(byteArrayExtra);
                b64KeyHandle = Base64.encodeToString(attestationResponse.getKeyHandle(), Base64.DEFAULT);
                clientDataJson = new String(attestationResponse.getClientDataJSON(), UTF_8);
                b64AttestationObject = Base64.encodeToString(attestationResponse.getAttestationObject(), Base64.DEFAULT);


                // store keyHandle
                pubkeyId.setText(b64KeyHandle);

                // propagate rpid
                rpId.setText(RPID);

                Log.d(LOG_TAG, "b64KeyHandle: " + b64KeyHandle);
                Log.d(LOG_TAG, "clientDataJson: " + clientDataJson);
                Log.d(LOG_TAG, "b64AttestationObject: " + b64AttestationObject);
                Log.d(LOG_TAG, "attestationObject:\n" + decodeAttestationObject(attestationResponse.getAttestationObject()));

                registerResult.setText("b64Keyhandle: " + b64KeyHandle +
                        "\n clientDataJson: " + clientDataJson +
                        "\n b64AttestationObject: " + b64AttestationObject +
                        "\n attestationObject:\n" + decodeAttestationObject(attestationResponse.getAttestationObject()));
                break;
            case SIGN_REQUEST_CODE:
                Log.d(LOG_TAG, "handleResponse: SIGN_REQUEST_CODE");

                AuthenticatorAssertionResponse assertionResponse = AuthenticatorAssertionResponse.deserializeFromBytes(byteArrayExtra);
                b64KeyHandle = Base64.encodeToString(assertionResponse.getKeyHandle(), Base64.DEFAULT);
                clientDataJson = new String(assertionResponse.getClientDataJSON(), UTF_8);
                b64Signature = Base64.encodeToString(assertionResponse.getSignature(), Base64.DEFAULT);
                b64UserHandle = (assertionResponse.getUserHandle() != null) ?
                        Base64.encodeToString(assertionResponse.getUserHandle(), Base64.DEFAULT) : "";
                b64authData = Base64.encodeToString(assertionResponse.getAuthenticatorData(), Base64.DEFAULT);

                java.util.Map<String, String> authDataMap = new HashMap<>();
                decodeAuthData(assertionResponse.getAuthenticatorData(), authDataMap);
                String authData = mapToString(authDataMap);

                Log.d(LOG_TAG, "b64KeyHandle: " + b64KeyHandle);
                Log.d(LOG_TAG, "clientDataJson: " + clientDataJson);
                Log.d(LOG_TAG, "b64Signature: " + b64Signature);
                Log.d(LOG_TAG, "b64UserHandle: " + b64UserHandle);
                Log.d(LOG_TAG, "b64authData: " + b64authData);
                Log.d(LOG_TAG, "authData:\n" + authData);

                signResult.setText("b64KeyHandle: " + b64KeyHandle +
                        "\n clientDataJson: " + clientDataJson +
                        "\n b64Signature: " + b64Signature +
                        "\n b64UserHandle: " + b64UserHandle +
                        "\n b64authData: " + b64authData +
                        "\n authData:\n" + authData);

                break;
            default:
                Toast.makeText(this, "Unknown status...", Toast.LENGTH_LONG).show();
        }
    }

    private void handleErrorResponse(byte[] byteArrayExtra, int requestCode) {
        TextView view = (requestCode == REGISTER_REQUEST_CODE) ? registerResult : signResult;
        AuthenticatorErrorResponse response = AuthenticatorErrorResponse.deserializeFromBytes(byteArrayExtra);
        String errorName = response.getErrorCode().name();
        String errorMessage = response.getErrorMessage();

        Log.d(LOG_TAG, "handleErrorResponse: errorName:" + errorName);
        Log.d(LOG_TAG, "handleErrorResponse: errorMessage:" + errorMessage);

        view.setText("Error happened. \ncode: " + errorName.toString()
                + "\nmessage: " + errorMessage);
    }

    private String decodeAttestationObject(byte[] attObj) throws Exception {
        List<DataItem> dataItems = CborDecoder.decode(attObj);
        String result = "";

        if (dataItems.size() == 1 && dataItems.get(0) instanceof Map) {

            java.util.Map<String, String> attestationMap = new HashMap<>();

            Map attObjMap = (Map) dataItems.get(0);
            for (DataItem key : attObjMap.getKeys()) {
                if (key instanceof UnicodeString) {
                    if (((UnicodeString) key).getString().equals("fmt")) {
                        UnicodeString value = (UnicodeString) attObjMap.get(key);
                        attestationMap.put("fmt", value.getString());
                    }
                    if (((UnicodeString) key).getString().equals("authData")) {
                        byte[] authData = ((ByteString) attObjMap.get(key)).getBytes();
                        decodeAuthData(authData, attestationMap);

                        int index = 32;
                        if ((/* flags */ authData[index] & 1 << 6) != 0) {
                            index += 5;
                            byte[] attData = new byte[authData.length - index];
                            System.arraycopy(authData, index, attData, 0, authData.length - index);
                            int tmpindex = 0;
                            if (attData.length < 18) throw new Exception("Invalid attData");

                            byte[] aaguid = new byte[16];
                            System.arraycopy(attData, 0, aaguid, 0, 16);
                            attestationMap.put("aaguid", Base64.encodeToString(aaguid, Base64.DEFAULT));
                            tmpindex += 16;

                            int length = (attData[tmpindex++] << 8) & 0xFF;
                            length += attData[tmpindex++] & 0xFF;
                            byte[] credentialId = new byte[length];
                            System.arraycopy(attData, tmpindex, credentialId, 0, length);

                            attestationMap.put("credentialId", Base64.encodeToString(credentialId, Base64.DEFAULT));

                        }
                    }
                    if (((UnicodeString) key).getString().equals("attStmt")) {
                        attestationMap.put("attStmt", attObjMap.get(key).toString());
                    }

                }
            }
            result += mapToString(attestationMap);
        }
        return result;
    }

    private void decodeAuthData(byte[] authData, java.util.Map<String, String> attestationMap) throws Exception {
        if (authData.length < 37) {
            throw new Exception("Invalid authData");
        }
        int index = 0;
        byte[] rpIdHash = new byte[32];
        System.arraycopy(authData, 0, rpIdHash, 0, 32);
        attestationMap.put("rpIdHash", Base64.encodeToString(rpIdHash, Base64.DEFAULT));

        index += 32;
        byte flags = authData[index++];
        attestationMap.put("UP", String.valueOf((flags & 1) != 0));
        attestationMap.put("UV", String.valueOf((flags & 1 << 2) != 0));
        attestationMap.put("AT", String.valueOf((flags & 1 << 6) != 0));
        attestationMap.put("ED", String.valueOf((flags & 1 << 7) != 0));
        attestationMap.put("count",
                String.valueOf(Ints.fromBytes(authData[index++], authData[index++], authData[index++], authData[index++])));
    }

    private String mapToString(java.util.Map<String, String> attestationMap) {
        String result = "";
        for (java.util.Map.Entry<String, String> entry : attestationMap.entrySet()) {
            result += "\t" + entry.getKey() + ": " + entry.getValue() + "\n";
        }
        return result;
    }

    public void registerFIDO2(View v) {
        Log.d(LOG_TAG, "registerFIDO2: start!");

        PublicKeyCredentialCreationOptions.Builder optionsBuilder = new PublicKeyCredentialCreationOptions.Builder()
                .setRp(new PublicKeyCredentialRpEntity(
                        RPID,
                        "FIDO2demo",
                        null))
                .setParameters(new ArrayList<PublicKeyCredentialParameters>(Arrays.asList(
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY.toString(), EC2Algorithm.ES256.getAlgoValue()),
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY.toString(), RSAAlgorithm.RS256.getAlgoValue())
                )
                ))
                .setUser(new PublicKeyCredentialUserEntity(
                        userName.getText().toString().getBytes(),
                        userName.getText().toString(),
                        null,
                        displayName.getText().toString()))
                .setChallenge(challenge());

        // authenticatorAtattachment
        Attachment attachment = null;
        if (platformRB.isChecked()) attachment = Attachment.PLATFORM;
        if (cross_platformRB.isChecked()) attachment = Attachment.CROSS_PLATFORM;
        if (attachment != null)
            optionsBuilder.setAuthenticatorSelection(new AuthenticatorSelectionCriteria.Builder().setAttachment(attachment).build());

        // userVerification
        // undef

        // attestationConveyancePreference
        AttestationConveyancePreference conveyancePref = null;
        if (noneRB.isChecked()) conveyancePref = AttestationConveyancePreference.NONE;
        if (directRB.isChecked()) conveyancePref = AttestationConveyancePreference.DIRECT;
        if (indirectRB.isChecked()) conveyancePref = AttestationConveyancePreference.INDIRECT;
        if (conveyancePref != null)
            optionsBuilder.setAttestationConveyancePreference(conveyancePref);

        // residentKey
        // undef

        // timeout
        if (!timeout1.getText().toString().matches(""))
            optionsBuilder.setTimeoutSeconds(Double.parseDouble(timeout1.getText().toString()));

        PublicKeyCredentialCreationOptions options = optionsBuilder.build();

        Fido2ApiClient fido2ApiClient = Fido.getFido2ApiClient(getApplicationContext());
        Task<Fido2PendingIntent> result = fido2ApiClient.getRegisterIntent(options);
        result.addOnSuccessListener(new OnSuccessListener<Fido2PendingIntent>() {
            @Override
            public void onSuccess(Fido2PendingIntent fido2PendingIntent) {
                if (fido2PendingIntent.hasPendingIntent()) {
                    try {
                        fido2PendingIntent.launchPendingIntent(activity, REGISTER_REQUEST_CODE);
                    } catch (IntentSender.SendIntentException e) {
                        Log.d(LOG_TAG, "onSuccess: Exception");
                        e.printStackTrace();
                    }
                }
            }
        });

        result.addOnFailureListener(new OnFailureListener() {
            @Override
            public void onFailure(@NonNull Exception e) {
                e.printStackTrace();
            }
        });

    }

    public void signFIDO2(View v) {
        Log.d(LOG_TAG, "signFIDO2: start!");

        byte[] keyHandle = null;
        // get stored keyHandle
        try {
            keyHandle = Base64.decode(pubkeyId.getText().toString(), Base64.DEFAULT);
        } catch (IllegalArgumentException e) {
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
            return;
        }


        // transports
        List<Transport> transports = new ArrayList<>();
        if (usbCB.isChecked()) transports.add(Transport.USB);
        if (nfcCB.isChecked()) transports.add(Transport.NFC);
        if (ble_classicCB.isChecked()) transports.add(Transport.BLUETOOTH_CLASSIC);
        if (ble_low_energyCB.isChecked()) transports.add(Transport.BLUETOOTH_LOW_ENERGY);


        PublicKeyCredentialRequestOptions.Builder optionsBuilder = new PublicKeyCredentialRequestOptions.Builder()
                .setAllowList(new ArrayList<PublicKeyCredentialDescriptor>(Arrays.asList(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.PUBLIC_KEY.toString(),
                                keyHandle,
                                transports)
                )))
                .setChallenge(challenge());

        // userVerification
        // undef

        // rpId
        optionsBuilder.setRpId(rpId.getText().toString());

        // timeout
        if (!timeout2.getText().toString().matches(""))
            optionsBuilder.setTimeoutSeconds(Double.parseDouble(timeout2.getText().toString()));

        PublicKeyCredentialRequestOptions options = optionsBuilder.build();

        Fido2ApiClient fido2ApiClient = Fido.getFido2ApiClient(getApplicationContext());
        Task<Fido2PendingIntent> result = fido2ApiClient.getSignIntent(options);

        result.addOnSuccessListener(new OnSuccessListener<Fido2PendingIntent>() {
            @Override
            public void onSuccess(Fido2PendingIntent fido2PendingIntent) {
                if (fido2PendingIntent.hasPendingIntent()) {
                    try {
                        fido2PendingIntent.launchPendingIntent(activity, SIGN_REQUEST_CODE);
                    } catch (IntentSender.SendIntentException e) {
                        e.printStackTrace();
                    }
                }
            }
        });

        result.addOnFailureListener(new OnFailureListener() {
            @Override
            public void onFailure(@NonNull Exception e) {
                e.printStackTrace();
            }
        });
    }


    private byte[] challenge() {
        return SecureRandom.getSeed(16);
    }

}

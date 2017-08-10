package com.ahujasahab.fingerprintunlock;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;
import android.support.v4.app.ActivityCompat;
import android.webkit.PermissionRequest;
import android.widget.TextView;

import java.security.Permission;

/**
 * Created by hp on 09-08-2017.
 */

class FingerprintHandler extends FingerprintManager.AuthenticationCallback {
    private final Context mContext;
    private final TextView mErrorTv;

    FingerprintHandler(Context context)
  {
      this.mContext=context;
      mErrorTv=(TextView)((FingerPrintActivity)context).findViewById(R.id.errortv);

  }

    public void startAuth(FingerprintManager fingerprintManager, FingerprintManager.CryptoObject cryptoObject)
    {
        CancellationSignal cancellationSignal=new CancellationSignal();
        if(ActivityCompat.checkSelfPermission(mContext, Manifest.permission.USE_FINGERPRINT)!= PackageManager.PERMISSION_GRANTED)
        {
            return;
        }
        fingerprintManager.authenticate(cryptoObject,cancellationSignal,0,this,null);
    }
    @Override
    public void onAuthenticationError(int errorCode, CharSequence errString) {
        super.onAuthenticationError(errorCode, errString);

    }

    @Override
    public void onAuthenticationFailed() {
        super.onAuthenticationFailed();
        mErrorTv.setText("Authentication failed");
    }

    @Override
    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
        super.onAuthenticationHelp(helpCode, helpString);
        mErrorTv.setText("Authentication help "+helpString);
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);
        mErrorTv.setText("Authentication complete");
        Intent intent=new Intent((FingerPrintActivity)mContext,MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK);
        intent.addFlags(Intent.FLAG_ACTIVITY_NO_ANIMATION);
        mContext.startActivity(intent);
    }
}

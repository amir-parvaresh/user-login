package com.example.userlogin.registration;

import com.example.userlogin.appuser.AppUser;
import com.example.userlogin.appuser.AppUserRole;
import com.example.userlogin.appuser.AppUserService;
import com.example.userlogin.registration.token.ConfirmationToken;
import com.example.userlogin.registration.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
@AllArgsConstructor
public class RegistrationService {
    private final EmailValidator emailValidator;
    private final AppUserService appUserService;
    private final ConfirmationTokenService confirmationTokenService;
    public String register(RegistrationRequest request)
    {
        boolean isValidEmail = emailValidator.test(request.getEmail());
        if(!isValidEmail){
            throw new IllegalStateException("email is not valid");
        }
        return appUserService.signUpUser(
                new AppUser(
                        request.getFirstName(),
                        request.getLastName(),
                        request.getEmail(),
                        request.getPassword(),
                        AppUserRole.USER
                )
        );
    }

    @Transactional
    public String confirmToken(String token) {
        Optional<ConfirmationToken> optionalConfirmationToken = Optional.ofNullable(confirmationTokenService
                .getToken(token)
                .orElseThrow(() -> new IllegalStateException("token not found")));
        if(optionalConfirmationToken.isPresent()){
            ConfirmationToken confirmationToken = optionalConfirmationToken.get();
            if(confirmationToken.getConfirmedAt() !=null){
                throw new IllegalStateException("Token Already confirmed");
            }
            else{
                LocalDateTime expiredAt = confirmationToken.getExpiredAt();
                if(expiredAt.isBefore(LocalDateTime.now())){
                    throw new IllegalStateException("Token Expired");
                }
                else{
                    confirmationToken.setConfirmedAt(LocalDateTime.now());
                    confirmationTokenService.saveConfirmationToken(confirmationToken);
                    appUserService.enableAppUser(confirmationToken
                    .getAppUser().getEmail());
                    return "confirmed";
                }
            }
        }
        else {
            throw new IllegalStateException("token not found");
        }
    }
}

import { DOCUMENT, LowerCasePipe, NgClass, NgFor, NgIf, UpperCasePipe } from '@angular/common';
import { Component, Inject, OnDestroy, OnInit } from '@angular/core';
import { FormsModule, NgForm } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { environment } from '@env/environment';
import { LocalizeRouterPipe, LocalizeRouterService } from '@gilsdav/ngx-translate-router';
import { TranslatePipe } from '@ngx-translate/core';
import { Subject, Subscription } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { LogingovplNotificationComponent } from '../../logingovpl/logingovpl-notification/logingovpl-notification.component';

import { toggleVertically } from '@app/animations';
import { FeatureFlagService } from '@app/services/feature-flag.service';
import { HighContrastModeEnum, HighContrastService } from '@app/services/high-contrast.service';
import { IErrorBackend } from '@app/services/models/error-backend';
import { getMfaErrorCode, MfaErrorCode, MfaLoginResult, MfaSetup, mfaQrImageSrc } from '@app/services/models/mfa';
import { NotificationsService } from '@app/services/notifications.service';
import { SeoService } from '@app/services/seo.service';
import { UserService } from '@app/services/user.service';
import { NotificationsFrontComponent } from '@app/shared/notifications-front/notifications-front.component';
import { NotificationsServerComponent } from '@app/shared/notifications-server/notifications-server.component';

/**
 * Login Component
 */
@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  animations: [toggleVertically],
  standalone: true,
  imports: [
    LogingovplNotificationComponent,
    NgIf,
    NgFor,
    NgClass,
    RouterLink,
    FormsModule,
    NotificationsServerComponent,
    NotificationsFrontComponent,
    UpperCasePipe,
    LowerCasePipe,
    LocalizeRouterPipe,
    TranslatePipe,
  ],
})
export class LoginComponent implements OnInit, OnDestroy {
  /**
   * User subscription of login component
   */
  userSubscription: Subscription;

  /**
   * Login error
   */
  error: IErrorBackend;

  /**
   * Redirect url on login error
   */
  redirectUrl: string;

  /**
   * Toggle for login view
   */
  isEmailLoginChoose = false;
  highContrastMode: HighContrastModeEnum;

  /**
   * Two-factor authentication step of the e-mail login:
   * 'code' - account has 2FA, enter app code or recovery code;
   * 'setup' - administrator requires 2FA, set up the authenticator app;
   * 'recoveryCodes' - setup finished, show recovery codes once.
   */
  mfaStep: 'none' | 'code' | 'setup' | 'recoveryCodes' = 'none';
  mfaSetup: MfaSetup | null = null;
  mfaQrSrc: string | null = null;
  mfaRecoveryCodes: string[] = [];
  mfaInvalidCode = false;
  private credentials: { email: string; password: string; remember: boolean } | null = null;
  destroy$: Subject<void> = new Subject<void>();

  /**
   * @ignore
   */
  constructor(
    private router: Router,
    private activeRoute: ActivatedRoute,
    private userService: UserService,
    private seoService: SeoService,
    private notificationsService: NotificationsService,
    private localizeRouterService: LocalizeRouterService,
    public featureFlagsService: FeatureFlagService,
    private highContrastService: HighContrastService,
    @Inject(DOCUMENT) private document: Document,
  ) {}

  /**
   * Sets META tags (title).
   * Initializes redirection URL.
   * Gets Csrf token
   */
  ngOnInit() {
    this.seoService.setPageTitleByTranslationKey(['Action.Login']);
    this.redirectUrl = this.activeRoute.snapshot.queryParamMap.get('redirect');
    this.userService.getCsrfToken().subscribe();
    this.highContrastService
      .getCurrentContrastMode()
      .pipe(takeUntil(this.destroy$))
      .subscribe((mode) => (this.highContrastMode = mode));
  }

  /**
   * Redirects user on form submit
   * @param {NgForm} form
   */
  onSubmit(form: NgForm) {
    if (form.invalid) {
      return;
    }

    this.notificationsService.clearAlerts();
    this.redirectUrl = this.activeRoute.snapshot.queryParams.redirect;
    this.credentials = { email: form.value.email, password: form.value.password, remember: !!form.value.rememberCheck };
    this.userService.login(this.credentials.email, this.credentials.password, this.credentials.remember).subscribe({
      next: () => this.navigateAfterLogin(),
      error: (error) => this.handleMfaError(error),
    });
  }

  /**
   * Second step: code from the authenticator app or a recovery code
   */
  onMfaCodeSubmit(form: NgForm) {
    if (form.invalid || !this.credentials) {
      return;
    }
    this.notificationsService.clearAlerts();
    this.mfaInvalidCode = false;
    const { email, password, remember } = this.credentials;
    this.userService.login(email, password, remember, String(form.value.otpCode).trim()).subscribe({
      next: () => this.navigateAfterLogin(),
      error: (error) => this.handleMfaError(error, form),
    });
  }

  /**
   * Setup required by the administrator: confirm the app with the first code
   */
  onMfaSetupSubmit(form: NgForm) {
    if (form.invalid || !this.credentials) {
      return;
    }
    this.notificationsService.clearAlerts();
    this.mfaInvalidCode = false;
    const { email, password, remember } = this.credentials;
    this.userService.confirmMfaSetupOnLogin(email, password, String(form.value.otpCode).trim(), remember).subscribe({
      next: (user) => {
        this.mfaRecoveryCodes = (user as unknown as MfaLoginResult)?.attributes?.recovery_codes || [];
        this.credentials = null;
        this.mfaStep = 'recoveryCodes';
      },
      error: (error) => this.handleMfaError(error, form),
    });
  }

  finishMfaSetup() {
    this.mfaRecoveryCodes = [];
    this.navigateAfterLogin();
  }

  cancelMfa() {
    this.credentials = null;
    this.mfaSetup = null;
    this.mfaQrSrc = null;
    this.mfaInvalidCode = false;
    this.mfaStep = 'none';
  }

  private handleMfaError(error: unknown, form?: NgForm) {
    const code = getMfaErrorCode(error);
    if (code === MfaErrorCode.Required) {
      this.mfaStep = 'code';
    } else if (code === MfaErrorCode.SetupRequired && this.credentials) {
      this.userService.startMfaSetupOnLogin(this.credentials.email, this.credentials.password).subscribe((setup) => {
        this.mfaSetup = setup;
        this.mfaQrSrc = mfaQrImageSrc(setup.qr_svg);
        this.mfaStep = 'setup';
      });
    } else if (code === MfaErrorCode.InvalidCode) {
      this.mfaInvalidCode = true;
      form?.resetForm();
    }
  }

  private navigateAfterLogin() {
    this.credentials = null;
    if (this.redirectUrl) {
      this.notificationsService.clearAlerts();
      this.router.navigateByUrl(this.redirectUrl);
    } else {
      this.router.navigate(this.localizeRouterService.translateRoute(['/!user', '!dashboard']) as []);
    }
  }

  chooseEmailLogin() {
    this.isEmailLoginChoose = true;
  }

  returnToLoginMethod() {
    this.isEmailLoginChoose = false;
    this.cancelMfa();
  }

  loginViaWk() {
    if (environment.production) {
      const currentUrl = this.document.location.hostname.replace('www.', '');
      window.location.href = `https://admin.${currentUrl}/logingovpl`;
    } else {
      window.location.href = `https://admin.mcod.local/logingovpl`;
    }
  }

  /**
   * Unsubscribes from existing subscriptions
   */
  ngOnDestroy() {
    if (this.userSubscription) {
      this.userSubscription.unsubscribe();
    }
    this.destroy$.next();
    this.destroy$.complete();
  }
}

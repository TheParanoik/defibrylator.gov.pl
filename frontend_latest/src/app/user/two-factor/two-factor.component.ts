import { DatePipe, NgClass, NgFor, NgIf } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { FormsModule, NgForm } from '@angular/forms';
import { TranslatePipe } from '@ngx-translate/core';

import { getMfaErrorCode, MfaErrorCode, MfaSetup, mfaQrImageSrc, MfaStatus } from '@app/services/models/mfa';
import { NotificationsService } from '@app/services/notifications.service';
import { SeoService } from '@app/services/seo.service';
import { UserService } from '@app/services/user.service';
import { NotificationsServerComponent } from '@app/shared/notifications-server/notifications-server.component';

/**
 * Two-factor authentication (authenticator app) for the e-mail + password login.
 * Status, setup, recovery codes and switching off (not allowed when required by the administrator).
 */
@Component({
  selector: 'app-two-factor',
  templateUrl: './two-factor.component.html',
  standalone: true,
  imports: [FormsModule, NgIf, NgFor, NgClass, DatePipe, NotificationsServerComponent, TranslatePipe],
})
export class TwoFactorComponent implements OnInit {
  status: MfaStatus | null = null;
  setup: MfaSetup | null = null;
  qrSrc: string | null = null;
  recoveryCodes: string[] = [];
  mode: 'view' | 'setup' | 'regenerate' | 'disable' = 'view';
  invalidCode = false;
  notAllowed = false;

  constructor(
    private userService: UserService,
    private notificationsService: NotificationsService,
    private seoService: SeoService,
  ) {}

  ngOnInit() {
    this.seoService.setPageTitleByTranslationKey(['Mfa.Title', 'MyDashboard.Self']);
    this.loadStatus();
  }

  loadStatus() {
    this.userService.getMfaStatus().subscribe((status) => (this.status = status));
  }

  startSetup() {
    this.resetMessages();
    this.recoveryCodes = [];
    this.userService.startMfaSetup().subscribe((setup) => {
      this.setup = setup;
      this.qrSrc = mfaQrImageSrc(setup.qr_svg);
      this.mode = 'setup';
    });
  }

  confirmSetup(form: NgForm) {
    if (form.invalid) {
      return;
    }
    this.resetMessages();
    this.userService.confirmMfaSetup(String(form.value.otpCode).trim()).subscribe({
      next: (status) => this.showResult(status),
      error: (error) => this.handleError(error, form),
    });
  }

  regenerateCodes(form: NgForm) {
    if (form.invalid) {
      return;
    }
    this.resetMessages();
    this.userService.regenerateMfaRecoveryCodes(String(form.value.otpCode).trim()).subscribe({
      next: (status) => this.showResult(status),
      error: (error) => this.handleError(error, form),
    });
  }

  disable(form: NgForm) {
    if (form.invalid) {
      return;
    }
    this.resetMessages();
    this.userService.disableMfa(form.value.password, String(form.value.otpCode).trim()).subscribe({
      next: (status) => this.showResult(status),
      error: (error) => this.handleError(error, form),
    });
  }

  setMode(mode: 'view' | 'regenerate' | 'disable') {
    this.resetMessages();
    this.mode = mode;
  }

  private showResult(status: MfaStatus) {
    this.recoveryCodes = status.recovery_codes || [];
    this.status = status;
    this.setup = null;
    this.qrSrc = null;
    this.mode = 'view';
  }

  private handleError(error: unknown, form: NgForm) {
    const code = getMfaErrorCode(error);
    this.invalidCode = code === MfaErrorCode.InvalidCode;
    this.notAllowed = code === MfaErrorCode.NotAllowed;
    form.resetForm();
  }

  private resetMessages() {
    this.notificationsService.clearAlerts();
    this.invalidCode = false;
    this.notAllowed = false;
  }
}

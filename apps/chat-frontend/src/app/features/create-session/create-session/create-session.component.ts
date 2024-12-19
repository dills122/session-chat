import { Component, ElementRef, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { NbGlobalPhysicalPosition, NbToastrService } from '@nebular/theme';
import { Observable, Subject, of, timer } from 'rxjs';
import { catchError, takeUntil, tap } from 'rxjs/operators';
import { EventStatuses } from 'shared-sdk';
import { ConfirmModalComponent } from 'src/app/core/confirm-modal/confirm-modal.component';
import { CryptoService } from 'src/app/services/crypto/crypto.service';
import { LinkGenerationService } from 'src/app/services/link-generation/link-generation.service';
import { LoginService } from 'src/app/services/login/login.service';
import { RoomManagementService } from 'src/app/services/room-management/room-management.service';

@Component({
  selector: 'td-create-session',
  templateUrl: './create-session.component.html',
  styleUrls: ['./create-session.component.scss']
})
export class CreateSessionComponent implements OnInit, OnDestroy {
  public participantUid: string;
  public ownersUid: string;
  public linkUrl$: Observable<string>;
  public hasLinkBeenGenerated = false;
  public hasSessionBeenCreated = false;
  public hasRoomIdBeenCreated = false;
  private roomId: string;
  private onDestroyNotifier = new Subject<void>();

  @ViewChild('session_confirmation') private modalComponent: ConfirmModalComponent;
  @ViewChild('generated_link') private linkComponent: ElementRef;

  constructor(
    private linkGenerationService: LinkGenerationService,
    private cryptoService: CryptoService,
    private loginService: LoginService,
    private toastrService: NbToastrService,
    private roomManagementService: RoomManagementService
  ) {}

  ngOnInit(): void {
    this.loginService.cleanUpSession();
    this.generateRoomId();
    this.subscribeToSessionCreation();
    this.registerLoginCallback();
  }

  ngOnDestroy(): void {
    this.onDestroyNotifier.next();
    this.onDestroyNotifier.complete();
  }

  private subscribeToSessionCreation(): void {
    this.roomManagementService
      .subscribeSessionCreation()
      .pipe(
        takeUntil(this.onDestroyNotifier),
        tap((resp) => {
          this.hasSessionBeenCreated = resp.status === EventStatuses.SUCCESS;

          if (this.hasSessionBeenCreated) {
            this.joinSession();
          } else {
            this.showErrorToast('Issue creating session, try again later', 'Session Creation Issue');
          }
        })
      )
      .subscribe();
  }

  private registerLoginCallback(): void {
    this.loginService
      .registerLoginCallback(this.ownersUid, null)
      .pipe(takeUntil(this.onDestroyNotifier))
      .subscribe();
  }

  createSession(): void {
    const participantLink = (this.linkComponent.nativeElement as HTMLInputElement).value;
    this.roomManagementService.createSession({
      roomId: this.roomId,
      creatorUId: this.ownersUid,
      validParticipantLinks: [participantLink]
    });
  }

  verifyConfirmModalResult(event: boolean): void {
    if (event) {
      this.createSession();
    }
  }

  joinSession(): void {
    if (!this.hasSessionBeenCreated) {
      this.showErrorToast('Issue joining session', 'Session Issue');
      return;
    }

    try {
      this.createTimeoutWarningTimer();
      this.loginService.login({
        uid: this.ownersUid,
        roomId: this.roomId,
        hash: this.linkGenerationService.createLinkHash({
          uid: this.ownersUid,
          roomId: this.roomId
        }),
        referrer: 'creator'
      });
    } catch (err) {
      console.error(err);
      this.showErrorToast('Issue joining session', 'Login Issue');
    }
  }

  openConfirmationModal(): void {
    this.modalComponent.open();
  }

  generateLink(): void {
    this.toggleLinkGeneration();

    if (this.hasRoomIdBeenCreated) {
      this.linkUrl$ = this.linkGenerationService
        .createLinkForSession({
          uid: this.participantUid,
          roomId: this.roomId
        })
        .pipe(
          catchError((err) => {
            console.warn(err);
            return of(); // TODO: Replace with proper error handling
          })
        );
    }
  }

  canCreateSession(): boolean {
    return this.hasLinkBeenGenerated && this.hasRoomIdBeenCreated && !!this.ownersUid?.length;
  }

  private generateRoomId(): void {
    this.roomId = this.cryptoService.GenerateRandomString();
    this.hasRoomIdBeenCreated = true;
  }

  toggleLinkGeneration(): void {
    this.hasLinkBeenGenerated = !this.hasLinkBeenGenerated;
  }

  private createTimeoutWarningTimer(): void {
    timer(10000) // Emits after 10 seconds
      .pipe(takeUntil(this.onDestroyNotifier))
      .subscribe(() => {
        this.showWarningToast('Login is taking awhile, try refreshing', 'Timeout');
      });
  }

  private showErrorToast(message: string, title: string): void {
    this.toastrService.danger(message, title, {
      position: NbGlobalPhysicalPosition.TOP_RIGHT
    });
  }

  private showWarningToast(message: string, title: string): void {
    this.toastrService.warning(message, title, {
      position: NbGlobalPhysicalPosition.TOP_RIGHT
    });
  }
}

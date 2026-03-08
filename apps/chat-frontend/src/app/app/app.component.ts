import { ChangeDetectionStrategy, Component } from '@angular/core';
import { ThemeService } from '../services/theme/theme.service';

@Component({
  selector: 'td-root',
  templateUrl: './app.component.html',
  standalone: false,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class AppComponent {
  constructor(private themeService: ThemeService) {}

  toggleTheme() {
    this.themeService.toggleTheme();
  }
}

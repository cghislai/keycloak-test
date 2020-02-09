import {NgModule} from '@angular/core';
import {RouterModule, Routes} from '@angular/router';
import {AuthenticationGuard} from './guard/authentication-guard';


const routes: Routes = [
  {
    path: '',
    pathMatch: 'full',
    redirectTo: '/welcome',
  },
  {
    path: '',
    canActivate: [AuthenticationGuard],
    children: [
      {
        path: 'welcome',
        loadChildren: () => import('./welcome/welcome.module').then(mod => mod.WelcomeModule)
      }
    ]
  }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule {
}

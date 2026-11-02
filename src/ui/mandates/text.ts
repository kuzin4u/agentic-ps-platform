// Тексты экрана мандатов (ru / en; правило совместимости 3). Коды Платформы на экран не выводятся как текст для
// человека — только через этот словарь.
export const TEXT = {
  ru: {
    title: "Мандаты агентов",
    signIn: "Войдите через приложение банка",
    linkInvalid: "Ссылка недействительна или устарела. Откройте экран из приложения банка ещё раз.",
    formExpired: "Форма устарела. Обновите страницу и повторите.",
    signOut: "Выйти",
    signedOut: "Вы вышли.",
  },
  en: {
    title: "Agent mandates",
    signIn: "Please sign in through your banking app",
    linkInvalid: "The link is invalid or has expired. Open the screen from your banking app again.",
    formExpired: "The form has expired. Reload the page and try again.",
    signOut: "Sign out",
    signedOut: "You have signed out.",
  },
} as const;

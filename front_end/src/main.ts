import './app.css'
import App from './App.svelte'

const targetElement = document.getElementById('app');

if (!targetElement) {
  throw new Error("Target element #app not found in the DOM.");
}

const app = new App({
  target: targetElement
})

export default app

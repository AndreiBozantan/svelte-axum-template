import './app.css'
import App from './App.svelte'
import { mount } from 'svelte'

const targetElement = document.getElementById('app');

if (!targetElement) {
  throw new Error("Target element #app not found in the DOM.");
}

const app = mount(App, {
  target: targetElement
})

export default app

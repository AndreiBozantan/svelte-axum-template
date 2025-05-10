<script lang="ts">
  import { onMount } from "svelte";
  import { user } from "./../ts/store";
  import { getSecure } from "./../ts/fetch";

  let response: string = '';

  onMount(async () => {
    response = await getSecure();
  });
</script>

<div>
  <container class="wider mobile">
    <p>Logged in as {$user}</p>
    <p class="mono">Response: {response}</p>
  </container>
</div>

<style>
  div {
    margin: 25px;
    display: flex;
    flex-direction: column;
    align-items: center;
  }

  @media only screen and (max-width: 620px) {
    container.mobile {
      width: 300px;
      word-wrap: break-word;
    }
  }
</style>

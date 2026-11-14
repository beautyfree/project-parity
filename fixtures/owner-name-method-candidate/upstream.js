class StageContentTexture {
  setContentIdentity(identity) {
    if (!this.content) {
      this.content = new StageProducedContent({
        ...identity,
        contentTexture: this,
        producedByEncoder: this.pendingEncoder,
      });
    } else {
      this.content.update(identity, this.pendingEncoder);
    }
    return this.content;
  }
}

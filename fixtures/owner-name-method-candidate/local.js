class StageContentTexture {
  _setContentIdentity(identity) {
    if (this.content) {
      this.content.update(identity, this.pendingEncoder);
      return this.content;
    }
    this.content = new StageProducedContent({
      ...identity,
      contentTexture: this,
      producedByEncoder: this.pendingEncoder,
    });
    return this.content;
  }
}

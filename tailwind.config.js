module.exports = {
  content: [
    "./templates/**/*.html",
    "./**/templates/**/*.html",
    "./**/*.py"
  ],
  theme: {
    extend: {
      fontFamily: {
        display: ["Space Grotesk", "sans-serif"],
        sans: ["IBM Plex Sans", "sans-serif"]
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(34, 211, 238, 0.15), 0 30px 80px rgba(8, 47, 73, 0.45)"
      }
    }
  },
  plugins: []
}
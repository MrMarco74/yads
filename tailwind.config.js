/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: ["./yads/api/templates/**/*.html"],
  theme: {
    extend: {
      colors: {
        gray: {
          900: "#111827",
          800: "#1f2937",
          700: "#374151",
        },
      },
    },
  },
  plugins: [],
}

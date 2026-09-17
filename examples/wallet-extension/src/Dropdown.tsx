/**
 * In-page dropdown.
 *
 * A native <select> hands its menu to the OS, which draws it outside the
 * extension popup, ignores the theme, and cannot show a logo or a balance
 * alongside each row. This renders the list inside the popup instead, scrolls
 * when it is long, and flips upward when there is no room below.
 *
 * Implements the combobox/listbox keyboard contract: arrows move, Enter picks,
 * Escape closes, Home/End jump, and focus returns to the trigger.
 */
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { ChevronDown, Check } from "lucide-react";

export interface DropdownOption {
  value: string;
  label: string;
  /** Right-aligned secondary text, e.g. a balance. */
  hint?: string;
  icon?: ReactNode;
}

export function Dropdown({
  value,
  options,
  onChange,
  ariaLabel,
  className = "",
}: {
  value: string;
  options: DropdownOption[];
  onChange: (value: string) => void;
  ariaLabel: string;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [flip, setFlip] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  const selectedIndex = Math.max(
    0,
    options.findIndex((option) => option.value === value),
  );
  const selected = options[selectedIndex];

  useEffect(() => {
    if (!open) return;
    setActive(selectedIndex);

    function onPointerDown(event: MouseEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onPointerDown);
    return () => document.removeEventListener("mousedown", onPointerDown);
  }, [open, selectedIndex]);

  // Open upward when the list would otherwise run past the popup's bottom edge.
  useLayoutEffect(() => {
    if (!open || !triggerRef.current) return;
    const rect = triggerRef.current.getBoundingClientRect();
    const below = window.innerHeight - rect.bottom;
    setFlip(below < Math.min(240, options.length * 46 + 12) && rect.top > below);
  }, [open, options.length]);

  useEffect(() => {
    if (!open) return;
    listRef.current
      ?.querySelectorAll("li")
      [active]?.scrollIntoView({ block: "nearest" });
  }, [open, active]);

  function choose(index: number) {
    const option = options[index];
    if (option) onChange(option.value);
    setOpen(false);
    triggerRef.current?.focus();
  }

  function onKeyDown(event: React.KeyboardEvent) {
    if (!open) {
      if (event.key === "ArrowDown" || event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        setOpen(true);
      }
      return;
    }
    switch (event.key) {
      case "Escape":
        event.preventDefault();
        setOpen(false);
        triggerRef.current?.focus();
        break;
      case "ArrowDown":
        event.preventDefault();
        setActive((i) => Math.min(options.length - 1, i + 1));
        break;
      case "ArrowUp":
        event.preventDefault();
        setActive((i) => Math.max(0, i - 1));
        break;
      case "Home":
        event.preventDefault();
        setActive(0);
        break;
      case "End":
        event.preventDefault();
        setActive(options.length - 1);
        break;
      case "Enter":
      case " ":
        event.preventDefault();
        choose(active);
        break;
    }
  }

  return (
    <div className={`dropdown ${className} ${open ? "open" : ""}`} ref={rootRef} onKeyDown={onKeyDown}>
      <button
        type="button"
        ref={triggerRef}
        className="dropdownTrigger"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={ariaLabel}
        onClick={() => setOpen((v) => !v)}
      >
        {selected?.icon}
        <span className="dropdownLabel">{selected?.label ?? ""}</span>
        {selected?.hint && <span className="dropdownHint">{selected.hint}</span>}
        <ChevronDown size={15} className="dropdownChevron" />
      </button>

      {open && (
        <ul
          className={`dropdownList ${flip ? "flip" : ""}`}
          role="listbox"
          aria-label={ariaLabel}
          ref={listRef}
          tabIndex={-1}
        >
          {options.map((option, index) => (
            <li
              key={option.value}
              role="option"
              aria-selected={option.value === value}
              className={`dropdownOption ${index === active ? "active" : ""} ${
                option.value === value ? "selected" : ""
              }`}
              onMouseEnter={() => setActive(index)}
              onClick={() => choose(index)}
            >
              {option.icon}
              <span className="dropdownLabel">{option.label}</span>
              {option.hint && <span className="dropdownHint">{option.hint}</span>}
              {option.value === value && <Check size={15} className="dropdownTick" />}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
